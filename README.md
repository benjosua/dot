# dot

`dot` is a Unix-first dotfile manager written in Rust.

It is designed around a few defaults:

- top-level directories are packages
- symlink is the default target kind
- `.tmpl` files render automatically
- state and render cache live in XDG directories, not in your repo
- planning is explicit and safe before mutation

## Commands

```text
dot init
dot plan [packages...]
dot apply [packages...]
dot status [packages...]
dot undeploy [packages...]
dot doctor [packages...]
```

Global flags:

```text
--repo <path>
--host <name>
--verbose
--json
--yes
--overwrite-unmanaged
--overwrite-drift
--allow-privileged
--no-render-diff
```

## Layout

With a Stow-style repo:

```text
dotfiles/
  zsh/
    .zshrc
  git/
    .config/git/config.tmpl
  assets/
    wallpaper.png
```

`dot plan` maps those files to:

- `zsh/.zshrc` -> `~/.zshrc`
- `git/.config/git/config.tmpl` -> `~/.config/git/config`
- `assets/wallpaper.png` -> `~/.local/share/...` only when you override it in `dot.toml`

## Config

`dot.toml` is optional. If present, it lets you override targets, kinds, modes, and selectors.

```toml
[settings]
default_kind = "symlink"
render_suffix = ".tmpl"
collision_policy = "error"

[settings.conflicts]
unmanaged = "block"
managed = "block"
privileged = "skip_package"
merge_tool = "opendiff"

[variables]
email = "user@example.test"

[packages.git.files."git/.config/git/config.tmpl"]
target = "~/.config/git/config"
kind = "render"

[packages.assets.files."assets/wallpaper.png"]
target = "~/.local/share/wallpaper.png"
kind = "copy"
mode = "0644"

[packages.machine.files."machine/.config/app/config.toml"]
target = "~/.config/app/config.toml"
kind = "render"
when.os = ["linux", "macos"]
when.host = ["laptop", "desktop"]

[packages.git.files."git/.config/git/config.tmpl".conflicts]
managed = "merge"

[packages.machine.conflicts]
privileged = "apply"
```

Conflict policy precedence is file -> package -> settings. Available actions are:

- `unmanaged = "block" | "overwrite" | "merge"`
- `managed = "block" | "overwrite" | "merge"`
- `privileged = "skip_package" | "apply"`

## Safety

- `plan` and `apply` share the same planner
- replacements are first-class operations
- unmanaged targets and managed drift are governed by explicit conflict policy
- `--overwrite-unmanaged` and `--overwrite-drift` are one-shot overrides
- merge-required conflicts print diff and merge-tool guidance without launching tools automatically
- packages that require privilege are skipped by default unless you pass `--allow-privileged`
- unreadable targets are surfaced as privileged inspection steps
- `apply` refuses to run when the planner reports validation errors

## Development

```text
cargo fmt
cargo test
```
