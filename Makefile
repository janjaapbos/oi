.PHONY: help test

help:
	@echo
	@echo "USAGE: make [target]"
	@echo
	@echo "TARGETS:"
	@echo
	@echo "  install        - install python package"
	@echo "  clean          - cleanup"
	@echo "  test           - run tests"
	@echo "  distribute     - upload to PyPI"
	@echo

install:
	@python setup.py install

test:
	@python -m unittest discover -s test

clean:
	@rm -rf build dist oi.egg-info

distribute:
	@python setup.py register -r pypi && python setup.py sdist upload -r pypi
