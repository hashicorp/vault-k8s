package version

var (
	// The main version number that is being run at the moment.
	//
	// Version must conform to the format expected by
	// github.com/hashicorp/go-version for tests to work.
	Version = "0.0.0"
)

// GetHumanVersion composes the parts of the version in a way that's suitable
// for displaying to humans.
func GetHumanVersion() string {
	// TODO: Make dev versions different from prod
	return Version
}
