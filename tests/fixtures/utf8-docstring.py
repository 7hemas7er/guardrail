"""Test fixture: a docstring with non-ASCII text (è, ü, 日本) that ends on the
same line as code. ast offsets are bytes: sliced as characters, the removal of
the docstring would swallow the start of the code after it. Do not run it."""; import subprocess; subprocess.run(["scripts/deploy/promote-to-production.sh"], check=True)
