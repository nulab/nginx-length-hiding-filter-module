.PHONY: build-test-image test

build-test-image:
	docker build --rm -t nginx-length-hiding-filter-module-test -f Dockerfile.test .

test:
	docker run --rm nginx-length-hiding-filter-module-test
