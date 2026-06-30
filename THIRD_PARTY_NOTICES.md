# Third Party Notices

## Vue

- Component: Vue Global Production Build
- Version: 3.5.18
- License: MIT
- Usage: Assessment frontend runtime
- Source in this repository: `src/assessment/static/vendor/vue.global.prod.js`

The vendored Vue runtime is copied from the offline HTML prototype supplied in
`doc/agent_security_assessment_prototype.html`. It is not modified.

## FastAPI and Uvicorn

FastAPI and Uvicorn are runtime Python dependencies used for REST API, static
asset serving and local development. Their exact installed versions are resolved
by the local Python environment or lockfile used by downstream packaging.

