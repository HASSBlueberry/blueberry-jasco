function transform(input) {
  // Keep the API request intact while normalizing the client supplied header.
  const headers = Object.assign({}, input.headers || {});
  headers['X-Blueberry-Device'] = 'jasco';
  return Object.assign({}, input, {headers: headers});
}
