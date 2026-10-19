[windows]
set shell := ["C:\\Program Files\\Git\\bin\\sh.exe","-c"]

# Fetch from remote origin using jj
pull:
    jj git fetch --remote origin

# Push to codeberg
push-codeberg:
    jj git push --tracked --remote codeberg

# Push to github
push-github:
    jj git push --tracked --remote origin

# Push to both github and gitlab
push: push-github push-codeberg

# Move changes to develop
move:
    jj b move -t '@-' develop

# Remove compilatiopn artifacts from previous
tidy:
    cargo sweep --installed

# Install the 3 binaries (old-crypto, sigabactl and kl7ctl)
install:
	cargo install --path crates/old-crypto-tui
	cargo install --path crates/sigaba
	cargo install --path crates/kl-7
	cargo install --path crates/purple
	cargo install --path crates/fialka
	cargo install --path crates/m209
