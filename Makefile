NODE = node
TEST = vows
TESTS ?= test/*-test.js test/**/*-test.js

test:
	@NODE_ENV=test NODE_PATH=lib $(TEST) $(TEST_FLAGS) $(TESTS)

docs: docs/api.html

docs/api.html: lib/passport-oauth/*.js
	dox \
		--title Passport-OAuth \
		--desc "OAuth 1.0 and 2.0 authentication strategies for Passport" \
		$(shell find lib/passport-oauth/* -type f) > $@

docclean:
	rm -f docs/*.{1,html}

.PHONY: test docs docclean
