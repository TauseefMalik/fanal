package analyzer

import (
	"os"
	"strings"
	"sync"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer/buildinfo/pyxis"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
)

var (
	analyzers       []analyzer
	configAnalyzers []configAnalyzer

	// ErrUnknownOS occurs when unknown OS is analyzed.
	ErrUnknownOS = xerrors.New("unknown OS")
	// ErrPkgAnalysis occurs when the analysis of packages is failed.
	ErrPkgAnalysis = xerrors.New("failed to analyze packages")
	// ErrNoPkgsDetected occurs when the required files for an OS package manager are not detected
	ErrNoPkgsDetected = xerrors.New("no packages detected")
)

type AnalysisTarget struct {
	FilePath string
	Content  []byte
}

type analyzer interface {
	Name() string
	Analyze(input AnalysisTarget) (*AnalysisResult, error)
	Required(filePath string, info os.FileInfo) bool
}

type configAnalyzer interface {
	Analyze(targetOS types.OS, content []byte) ([]types.Package, error)
	Required(osFound types.OS) bool
}

func RegisterAnalyzer(analyzer analyzer) {
	analyzers = append(analyzers, analyzer)
}

func RegisterConfigAnalyzer(analyzer configAnalyzer) {
	configAnalyzers = append(configAnalyzers, analyzer)
}

type Opener func() ([]byte, error)

// BuildInfo represents information under /root/buildinfo in RHEL
type BuildInfo struct {
	ContentSets []string
	Nvr         string
	Arch        string
}

type AnalysisResult struct {
	m            sync.Mutex
	OS           *types.OS
	PackageInfos []types.PackageInfo
	Applications []types.Application

	// for Red Hat
	BuildInfo *BuildInfo
}

func (r *AnalysisResult) isEmpty() bool {
	return r.OS == nil && len(r.PackageInfos) == 0 && len(r.Applications) == 0 && r.BuildInfo == nil
}

func (r *AnalysisResult) Merge(new *AnalysisResult) {
	if new == nil || new.isEmpty() {
		return
	}

	// this struct is accessed by multiple goroutines
	r.m.Lock()
	defer r.m.Unlock()

	if new.OS != nil {
		// OLE also has /etc/redhat-release and it detects OLE as RHEL by mistake.
		// In that case, OS must be overwritten with the content of /etc/oracle-release.
		// There is the same problem between Debian and Ubuntu.
		if r.OS == nil || r.OS.Family == aos.RedHat || r.OS.Family == aos.Debian {
			r.OS = new.OS
		}
	}

	if len(new.PackageInfos) > 0 {
		r.PackageInfos = append(r.PackageInfos, new.PackageInfos...)
	}

	if len(new.Applications) > 0 {
		r.Applications = append(r.Applications, new.Applications...)
	}

	if new.BuildInfo != nil {
		r.BuildInfo = new.BuildInfo
	}
}

// FillContentSets fills content sets from /root/buildinfo/Dockerfile-*
func (r *AnalysisResult) FillContentSets() (err error) {
	if r.BuildInfo == nil {
		r.BuildInfo = &BuildInfo{}
		return nil
	}
	// Only when content manifests don't exist, but Dockerfile in the layer
	if len(r.BuildInfo.ContentSets) == 0 && r.BuildInfo.Nvr != "" {
		p := pyxis.NewPyxis()
		r.BuildInfo.ContentSets, err = p.FetchContentSets(r.BuildInfo.Nvr, r.BuildInfo.Arch)
		if err != nil {
			return xerrors.Errorf("unable to fetch content sets: %w", err)
		}
	}
	return nil
}

func AnalyzeFile(filePath string, info os.FileInfo, opener Opener) (*AnalysisResult, error) {
	result := new(AnalysisResult)
	for _, analyzer := range analyzers {
		// filepath extracted from tar file doesn't have the prefix "/"
		if !analyzer.Required(strings.TrimLeft(filePath, "/"), info) {
			continue
		}
		b, err := opener()
		if err != nil {
			return nil, xerrors.Errorf("unable to open a file (%s): %w", filePath, err)
		}

		ret, err := analyzer.Analyze(AnalysisTarget{FilePath: filePath, Content: b})
		if err != nil {
			continue
		}
		result.Merge(ret)
	}
	return result, nil
}

func AnalyzeConfig(targetOS types.OS, configBlob []byte) []types.Package {
	for _, analyzer := range configAnalyzers {
		if !analyzer.Required(targetOS) {
			continue
		}

		pkgs, err := analyzer.Analyze(targetOS, configBlob)
		if err != nil {
			continue
		}
		return pkgs
	}
	return nil
}

func CheckPackage(pkg *types.Package) bool {
	return pkg.Name != "" && pkg.Version != ""
}
