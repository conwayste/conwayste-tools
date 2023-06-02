jupyter-no-output
=================

## What is this?

This is a pre-commit hook to ensure the Jupyter Notebooks in the
`nwv2-python-wrapper` folder of the `conwayste` repository do not have any
output in them.

## Do I need this?

No, unless you are running the Jupyter Notebooks and committing changes to them
to the Conwayste project.

## How do I use this?

First, install [rust-script](https://rust-script.org/#installation) if you have
not already done so. Then, copy `jupyter-no-output.rs` to
`.git/hooks/pre-commit` inside the `conwayste` repo (**not the conwayste-tools repo**).
If you commit and you have output in your Jupyter Notebook(s), it will refuse
to commit, and give you instructions for fixing.
