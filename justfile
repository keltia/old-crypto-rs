# Fetch from remote origin using jj
pull:
    jj git fetch --remote origin

# Push to github
push:
    jj git push --tracked --remote origin


# Move changes to develop
move:
    jj b move --to @- main
