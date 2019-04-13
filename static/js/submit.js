$(function() {
    $('#submit_scoresheet').bind('click', function() {
  // Stop form from submitting normally
  event.preventDefault();

  if($('input[name="subject_name"]').val() == ""){
    alert("you must provide the subject name");
  }

  else if($('#your_class').find(":selected").val() ==""){
    alert("you must provide the scoresheet's class");
  }

   else if($('input[name="subject_teacher"]').val() ==""){
    alert("you must provide the subject teacher");
  }
  else{
      $.post( $SCRIPT_ROOT + '/subject_check',{
        subject_name: $('input[name="subject_name"]').val(),class_id:$('#your_class').find(":selected").val()
      }, function(data) {
          if (data == "false")
          {alert("scoresheet already submitted")}
          else{$("#submit_score").submit();
};
      });};
      });
});