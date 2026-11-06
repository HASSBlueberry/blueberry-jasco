function transform(input) {
  const headers = Object.assign({}, input.headers || {});
  headers['X-Blueberry-Proxy'] = 'blueberryProxy';
  return Object.assign({}, input, {headers: headers});
}
