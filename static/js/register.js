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

var myInput = document.getElementById("admin");
var letter = document.getElementById("letter");
var capital = document.getElementById("capital");
var number = document.getElementById("number");
var length = document.getElementById("length");
var lowerCaseLetters = /[a-z]/g;
var upperCaseLetters = /[A-Z]/g;
var numbers = /[0-9]/g;

var myInput2 = document.getElementById("psw");
var length2 = document.getElementById("length2");




// When the user clicks on the password field, show the message box
myInput.onfocus = function() {
  document.getElementById("message").style.display = "block";
}

// When the user clicks outside of the password field, hide the message box
myInput.onblur = function() {
  document.getElementById("message").style.display = "none";
}


// When the user starts to type something inside the password field
myInput.onkeyup = function() {
  // Validate lowercase letters
  if(myInput.value.match(lowerCaseLetters)) {  
    letter.classList.remove("invalid");
    letter.classList.add("valid");
  } else {
    letter.classList.remove("valid");
    letter.classList.add("invalid");
  }
  
  // Validate capital letters
  if(myInput.value.match(upperCaseLetters)) {  
    capital.classList.remove("invalid");
    capital.classList.add("valid");
  } else {
    capital.classList.remove("valid");
    capital.classList.add("invalid");
  }

  // Validate numbers
  if(myInput.value.match(numbers)) {  
    number.classList.remove("invalid");
    number.classList.add("valid");
  } else {
    number.classList.remove("valid");
    number.classList.add("invalid");
  }
  
  // Validate length
  if(myInput.value.length >= 8) {
    length.classList.remove("invalid");
    length.classList.add("valid");
  } else {
    length.classList.remove("valid");
    length.classList.add("invalid");
  }
};
  


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
  



  function validateEmail(email) {
  var re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  return re.test(email);
}


$(function() {
    $('#submit_registration').bind('click', function() {
  // Stop form from submitting normally
  event.preventDefault();
  


  if($('input[name="username"]').val() == ""){
    alert("you must provide a username");
  }

  
  else if($('input[name="school_name"]').val() ==""){
    alert("you must provide a school name");
  }
  else if($('input[name="email"]').val() ==""){
    alert("you must provide a email");
  }
    else if($('input[name="school_session"]').val() ==""){
    alert("you must provide current school session");
  }
    else if($('input[name="term"]').val() ==""){
    alert("you must provide a current school term");
  }
  else if($('input[name="firstname"]').val() ==""){
    alert("you must provide your firstname");
  }
    else if($('input[name="surname"]').val() ==""){
    alert("you must provide your surname");
  }
    
  else if(validateEmail($('input[name="email"]').val()) !=true){
    alert("email not valid");
  }
  else if($('input[name="admin_password"]').val() ==""){
    alert("you must provide a password for admin");
  }
   else if($('input[name="phone_number"]').val() ==""){
    alert("you must provide a phone number");
  }
   else if($('input[name="address"]').val() ==""){
    alert("you must provide an address");
  }
   else if($('input[name="password"]').val() ==""){
    alert("you must provide a password");
  }
   else if($('input[name="confirmation"]').val() ==""){
    alert("you must provide a password");
  }
   else if($('input[name="admin_confirmation"]').val() ==""){
    alert("you must provide a password");
  }
   else if($('input[name="state"]').val() ==""){
    alert("you must provide state");
  } 
  else if($('input[name="city"]').val() ==""){
    alert("you must provide city");
  }
   else if($('input[name="password"]').val() != $('input[name="confirmation"]').val()){
    alert("password and confirmation do not match");
  }
  else if($('input[name="admin_password"]').val() != $('input[name="admin_password_confirmation"]').val()){
    alert("admin password and confirmation do not match");
  }
    else if($('input[name="admin_password"]').val() == $('input[name="password"]').val()){
    alert("your admin password must be different from staff password");
  }
  
    // Validate lowercase letters
 else if (!(myInput.value.match(lowerCaseLetters))) {  
    alert("admin password must contain lower case(small) letters");
  }
  
  // Validate capital letters
  else if(!(myInput.value.match(upperCaseLetters))) {  
      alert("admin password must contain upper (capital) letters");
    
  }

  // Validate numbers
  else if(!(myInput.value.match(numbers))) {
    alert("admin password must contain numbers");
  }
  
  // Validate length
 else if(myInput.value.length < 8) {
    alert("admin password must be up to 8 digits");
  }
      // Validate length
  else if(myInput2.value.length < 8) {
    alert(" password must be up to 8 digits");
  }


 else{     
    
      $.post( $SCRIPT_ROOT + '/username_check',{
        username: $('input[name="username"]').val()
      }, function(data) {
          if (data == "false")
          {alert("username already taken")}
          else{ $.post( $SCRIPT_ROOT + '/email_check',{
        email: $('input[name="email"]').val()
      }, function(data) {
          if (data == "false")
          {alert("email already belongs to another account")}
          else{$("#register").submit();
};
      });};
      });
  
      

     
 }
    });
  });
  


