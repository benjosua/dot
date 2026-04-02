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
```

## Safety

- `plan` and `apply` share the same planner
- replacements are first-class operations
- unmanaged drift is blocked until you confirm with `--yes`
- unreadable targets are surfaced as privileged inspection steps
- `apply` refuses to run when the planner reports validation errors

## Development

```text
cargo fmt
cargo test
```
