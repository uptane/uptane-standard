#!/bin/sh

set -e

if [ -z "$ACCESS_TOKEN" ]
then
  echo "Error: Needs an access token with commit rights to uptane/uptane-standard set as ACCESS_TOKEN."
  exit 1
fi

git config --global user.email "noreply@uptane.github.io" && \
git config --global user.name "Uptane CI" && \

git clone "https://${ACCESS_TOKEN}@github.com/uptane/uptane-standard.git" && \
cd uptane-standard && \
make html plaintext && \
mkdir build_tmp && \
mv uptane-standard.html uptane-standard.txt uptane-standard.xml build_tmp/ && \
git checkout gh-pages && \
mv build_tmp/* . && \
git commit -am "Rendered documents from commit $(git rev-parse master)" --quiet && \
git push origin gh-pages && \
echo "Deployment succesful!"
