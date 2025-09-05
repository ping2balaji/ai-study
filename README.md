# ai-study

## Setup

### setup python environment
You can do git clone of this repository and perform following to setup same environment using the power "UV"

uv is a fast Python package and project manager (from Astral) — it’s designed to be a modern replacement for pip, pip-tools, and even some parts of poetry or pipenv.

It automatically manages:
    - Virtual environments
    - Dependency resolution
    - Lockfiles

It’s written in Rust, so it’s very fast
```
git clone <repo-link>
cd <folder>
uv sync 
```
thats all!!

Note: 
If you really want to know the python packages came as part of this uv environment please check output of following command:
```uv pip tree```

### checking python version
You can check the python version and binary used for this project by running following command:
```uv run python -c "import sys; print(sys.executable, sys.version)"```


