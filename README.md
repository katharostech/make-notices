# Make Notices

A simple tool to create `3rd-party-notices.{html,json,md}` files based on your `cargo` and `pnpm`
dependencies.

Command outputs JSON, HTML, and Markdown attribution files. For an example see the [3rd party
notices](https://katharostech.github.io/make-notices/3rd-party-notices.html) for this project.

Before you run the tool you need to create a `notice.toml` file with at least the list of allowed
licenses. Here is an example with the default options:

```toml
allowed_licenses = []

# Useful if you have private packages that you want the tool to ignore
ignore_packages = []

export_markdown = true
export_json = true
export_html = true

# This means that we will get `3rd-party-notices.md`, `3rd-party-notices.json`, and
# `3rd-party-notices.html` files created in the current directory.
out_dir = "."
filename = "3rd-party-notices"
```

NONE OF THE OUTPUT OF THIS TOOL CONSTITUTES LEGAL ADVICE. WE ARE NOT RESPONSIBLE IF THIS CRATE FAILS
TO CREATE PROPER ATTRIBUTIONS FOR ALL OF YOUR DEPENDENCIES.
