// static/dom-vuln.js
// This demonstrates a DOM-based XSS vulnerability: reading location.hash and writing it with innerHTML.
(function(){
  function unsafeInject(text){
    var el = document.getElementById('injected');
    // INTENTIONALLY UNSAFE: using innerHTML with untrusted input
    el.innerHTML = text;
  }

  // read hash minus leading '#'
  var payload = location.hash ? location.hash.substring(1) : '';
  if(payload){
    unsafeInject(decodeURIComponent(payload));
  }
})();
