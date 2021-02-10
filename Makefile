clean:
	rm -rf build/
	rm -rf dist/
	coverage erase
	rm -rf nosetests.xml
	rm -rf htmlcov
	rm -rf coverage.xml
	rm -rf *egg-info
	find . -name '*.pyc' | while read line; do rm "$$line"; done

test: clean
#	nosetests --with-xunit -v
#	coverage erase
#	coverage run -m pytest -v
#	coverage xml --include="./*" --omit="./test*"
#	coverage html --include="./*" --omit="./test*"  

sonar: test
	sonar-scanner


build: 
	python3 setup.py sdist bdist_wheel

rebuild: clean build

install:
	pip3 install dist/*.tar.gz

uninstall:
	pip3 uninstall -y $$(grep name setup.py | cut -d'"' -f 2| cut -d'"' -f 1)
