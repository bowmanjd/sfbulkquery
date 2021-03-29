(() => {
  let apipath = '/services/data/';
  if (location.pathname === apipath) {
    let sessid = (';' + document.cookie).split('; sid=')[1].split('; ')[0];
    let domain = location.host;
    let output = JSON.stringify([domain, sessid]);
    navigator.clipboard.writeText(output);
  } else {
    window.open(location.origin + apipath, '_blank');
  }
})();
