.PHONY: clean help html xml open plaintext html-docker xml-docker open-docker plaintext-docker
.DEFAULT_GOAL := help

OPEN=$(word 1, $(wildcard /usr/bin/xdg-open /usr/bin/open /bin/echo))
MKD := uptane-standard.md
HTML := uptane-standard.html
RAWHTML := uptane-standard-raw.html
XML := uptane-standard.xml
TXT := uptane-standard.txt
RAWTXT := uptane-standard.raw.txt

clean: ## Remove the generated files
	@rm -rf $(HTML) $(XML) $(TXT) .refcache/

help: ## Print this message and exit
	@echo "\033[1;37mRequires Docker or 'gem install kramdown-rfc2629' and 'apt-get install xml2rfc'\033[0m"
	@awk 'BEGIN {FS = ":.*?## "} /^[0-9a-zA-Z_-]+:.*?## / {printf "\033[36m%s\033[0m : %s\n", $$1, $$2}' $(MAKEFILE_LIST) \
		| column -s ':' -t

open: html ## Create an HTML version from the markdown, then open it in a browser
	@$(OPEN) $(HTML)

html: xml ## Create an HTML version from the markdown
	@xml2rfc --html $(XML) $(HTML)
	@mv $(HTML) $(RAWHTML)
	@cat $(RAWHTML) |sed '/<table class="header">/,/<\/table>/d;/<h1 id="rfc.status">/,/except as an Internet-Draft.<\/p>/d' > $(HTML)
	@rm $(RAWHTML)

xml: ## Create an XML version from the markdown
	@kramdown-rfc2629 $(MKD) > $(XML)

plaintext: xml ## Create an RFC plaintext version from the markdown
	@xml2rfc $(XML) $(TXT) --raw
	@cat $(RAWTXT) |sed '/Status of This Memo/,/may not be published except as an Internet-Draft/d' |tail -n +10 > $(TXT)
	@rm $(RAWTXT)

open-docker: html-docker ## Create an HTML version from the markdown using docker, then open it in a browser
	@$(OPEN) $(HTML)

html-docker: xml-docker ## Create an HTML version from the markdown, using docker
	@docker run --rm -it -w /workdir -v $(PWD):/workdir advancedtelematic/rfc2629 xml2rfc --html $(XML) $(HTML)
	@mv $(HTML) $(RAWHTML)
	@cat $(RAWHTML) |sed '/<table class="header">/,/<\/table>/d;/<h1 id="rfc.status">/,/except as an Internet-Draft.<\/p>/d' > $(HTML)
	@rm $(RAWHTML)

xml-docker: ## Create an XML version from the markdown, using docker
	@docker run --rm -it -w /workdir -v $(PWD):/workdir advancedtelematic/rfc2629 kramdown-rfc2629 $(MKD) > $(XML)

plaintext-docker: xml-docker ## Create an RFC plaintext version from the markdown, using docker
	@docker run --rm -it -w /workdir -v $(PWD):/workdir advancedtelematic/rfc2629 xml2rfc $(XML) $(TXT) --raw
	@cat $(RAWTXT) |sed '/Status of This Memo/,/may not be published except as an Internet-Draft/d' |tail -n +10 > $(TXT)
	@rm $(RAWTXT)
