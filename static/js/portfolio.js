  
$(function() {
    $('#create_button').bind('click', function() {
  // Stop form from submitting normally
  event.preventDefault();
  
 if($('input[name="class_name"]').val() ==""){
    alert(" provide your class name ");
  }
   else if($('#section').find(":selected").val() ==""){
    alert(" provide your class section ");
  }
   else if($('input[name="no_of_students"]').val() ==""){
    alert(" provide the number of students in your class");
  }
  else if (isNaN($('input[name="no_of_students"]')) == false){
    alert(" The number of students must be a number");
  }
       else if($('input[name="ca"]').val() ==""){
    alert(" provide your maximum ca score");
  }
    else if (isNaN($('input[name="ca"]'))== false){
    alert(" maximum ca score must be a number");
  }
       else if($('input[name="test"]').val() ==""){
    alert(" provide your maximum test score");
  }
      else if (isNaN($('input[name="test"]'))==false){
    alert(" maximum test score must be a number");
  }
  else if($('input[name="exam"]').val() ==""){
    alert(" provide your maximum exam score");
  }
    else if (isNaN($('input[name="exam"]'))==false){
    alert(" maximum exam score must be a number");
  }
  else if((parseInt($('input[name="exam"]').val(), 10)+parseInt($('input[name="ca"]').val(), 10) + parseInt($('input[name="test"]').val(), 10)) != 100 ){
    alert("total score should be 100");
  }
     else if($('input[name="firstname"]').val() ==""){
    alert(" provide your firstname");
  }
  else if($('input[name="surname"]').val() ==""){
    alert(" provide your surname");
  }

     else if($('input[name="password"]').val() ==""){
    alert(" choose a password for your class");
  }
     else if($('input[name="confirmation"]').val() ==""){
    alert(" confirm your password");
  }

   else if($('input[name="password"]').val() != $('input[name="confirmation"]').val()){
    alert("password and confirmation do not match");
  }
else{
  $.post( $SCRIPT_ROOT + '/class_name',{
    classname: $('input[name="class_name"]').val(),
  }, function(data) {
      if (data == "fail"){alert("class already exist")}
      else{
        $("#create_form").submit();
      }
  });}

});
});
