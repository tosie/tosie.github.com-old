function titleize() {
  var input = $F('heading');
  new Ajax.Request('titleize.php', {
    postBody: 'input=' + input,
    onSuccess: function(transport) {
      var result = $('result');
      result.update(transport.responseText);
    }
  });
}