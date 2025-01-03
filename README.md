# WPKA - Wayland Polkit-Agent

WPKA is a general purpose polkit-agent for wayland that let's you use your favorit input to enter your password.

## Installation

### Arch

```bash
yay -S wpka
```

Make sure to reload dbus `sudo systemctl reload dbus` after installation.

### Autostart

Autostart `sudo wpka <your input cmd>` however you want. F.e. `sudo wpka walker -y` or `sudo wpka fuzzel --dmenu --password`.
