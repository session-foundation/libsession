# Sourced by the packaging scripts.

# Prints the archive name $1 with any TAG in it replaced by the release tag being built, or else by
# the build's time and commit -- the CI build's when there is one, so that every archive from one
# build agrees, and the current ones otherwise.
archive_name() {
    local tag
    if [ -n "$CI_COMMIT_TAG" ]; then
        tag="$CI_COMMIT_TAG"
    elif [ -n "$CI_COMMIT_SHA" ]; then
        tag="$(date --date=@$CI_PIPELINE_CREATED +%Y%m%dT%H%M%SZ)-${CI_COMMIT_SHA:0:9}"
    else
        tag="$(date +%Y%m%dT%H%M%SZ)-$(git rev-parse --short=9 HEAD)"
    fi
    echo "${1/TAG/$tag}"
}
