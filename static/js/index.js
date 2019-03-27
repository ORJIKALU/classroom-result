$('.form').find('input, textarea').on('keyup blur focus', function (e) {
  
  var $this = $(this),
      label = $this.prev('label');

	  if (e.type === 'keyup') {
			if ($this.val() === '') {
          label.removeClass('active highlight');
        } else {
          label.addClass('active highlight');
        }
    } else if (e.type === 'blur') {
    	if( $this.val() === '' ) {
    		label.removeClass('active highlight'); 
			} else {
		    label.removeClass('highlight');   
			}   
    } else if (e.type === 'focus') {
      
      if( $this.val() === '' ) {
    		label.removeClass('highlight'); 
			} 
      else if( $this.val() !== '' ) {
		    label.addClass('highlight');
			}
    }

});

$('.tab a,.links a').on('click', function (e) {
  
  e.preventDefault();
  
  $(this).parent().addClass('active');
  $(this).parent().siblings().removeClass('active');
  
  target = $(this).attr('href');

  $('.tab-content > div').not(target).hide();
  
  $(target).fadeIn(600);
  
});

addEventListener("load", function() { 
  setTimeout(hideURLbar, 0); }, false); function hideURLbar(){ window.scrollTo(0,1); } 
  
addEventListener("load", function() 
{ setTimeout(hideURLbar, 0); }, false); function hideURLbar(){ window.scrollTo(0,1); } 

$(function() {
    $('#login').bind('click', function() {
  // Stop form from submitting normally
  event.preventDefault();
  if($('input[name="username"]').val() == ""){
    alert("you must provide a username");
  }
  
 else if($('input[name="password"]').val() ==""){
    alert("you must provide a password");
  }
 else{
      $.post( $SCRIPT_ROOT + '/login_check',{
        username: $('input[name="username"]').val(),
        password: $('input[name="password"]').val()
      }, function(data) {
          if (data == "fail"){alert("invalid username or password")}
          else{
            $("#login_form").submit();
          }
      });}
    });
  });
  
var myInput2 = document.getElementById("psw");
var length2 = document.getElementById("length2");
// When the user clicks on the password field, show the message box
myInput2.onfocus = function() {
  document.getElementById("message2").style.display = "block";
};

// When the user clicks outside of the password field, hide the message box
myInput2.onblur = function() {
  document.getElementById("message2").style.display = "none";
};


// When the user starts to type something inside the password field
myInput2.onkeyup = function() {

  // Validate length
  if(myInput2.value.length >= 8) {
    length2.classList.remove("invalid");
    length2.classList.add("valid");
  } else {
    length2.classList.remove("valid");
    length2.classList.add("invalid");
  }
};





  
$(function() {
    $('#but').bind('click', function() {
  // Stop form from submitting normally
  event.preventDefault();
  
 if($('input[name="password"]').val() ==""){
    alert("you must provide a password");
  }
   else if($('input[name="confirmation"]').val() ==""){
    alert("you must provide a password confirmation");
  }
   else if($('input[name="password"]').val() != $('input[name="confirmation"]').val()){
    alert("password and confirmation do not match");
  }
// Validate length
  else if(myInput2.value.length < 8) {
    alert(" password must be up to 8 digits");
  }
  else{
    $("#change_form").submit();
  }
});
});