package auth

func mkHtml(body string) string {
	return `<!DOCTYPE html>
	<meta charset="utf-8">
	<body>
	<style>
	* {
		-webkit-box-sizing: border-box;
		-moz-box-sizing: border-box;
		box-sizing: border-box;
	}
	</style>
	` + body
}

const LoginForm = `
<form id=login action="" method="POST">
	Name or email:
	<p>
		<input type="text" name="username" />
	</p>
	Password:	
	<p>
		<input type="password" name="password" />
	</p>
	<button type="submit">Submit</button>
</form>

<script>

function getURLParameter(name) {
    return decodeURIComponent((new RegExp('[?|&]' + name + '=' + '([^&;]+?)(&|#|;|$)').exec(location.search)||[,""])[1].replace(/\+/g, '%20'))||null;
}

(function () {
  if (window.location.search.indexOf('invite=') !== -1) {
    var invite = getURLParameter("invite"),
        loginForm = document.querySelector("#login"),
        post = window.location+'?='+invite;
    loginForm.setAttribute("action", post);
})();

</script>

`
