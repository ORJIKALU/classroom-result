$(function() {
    $('#email_submit').bind('click', function() {
        // Stop form from submitting normally
  event.preventDefault();

     if($('#email_name').val() ==""){
        alert("provide the email you registered with");
      }
      else{
      $.post( $SCRIPT_ROOT + '/email_ajax',{
        email: $('input[name="email"]').val(),
      }, function(data) {
          if (data == "fail"){alert("no account is account is associated with this email")}
          else{
            $("#email_check").submit();
          }
      });}
      
    });
});
