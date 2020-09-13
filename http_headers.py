import requests

class ScanHeaders:

	def __init__(self, url):
		self.url = url
		response = requests.get(self.url)
		self.headers = response.headers
		self.cookies = response.cookies

	def scan_xxss(self):
		"""config failure if X-XSS-Protection header is not present"""
		try:
			if self.headers["X-XSS-Protection"]:
				print("[+]", "X-XSS-Protection", ':', "pass")
		except KeyError:
			print("[-]", "X-XSS-Protection header not present", ':', "fail!")

	def scan_nosniff(self):
		"""X-Content-Type-Options should be set to 'nosniff' """
		try:
			if self.headers["X-Content-Type-Options"].lower() == "nosniff":
				print("[+]", "X-Content-Type-Options", ':', "pass")
			else:
				print("[-]", "X-Content-Type-Options header not set correctly", ':', "fail!")
		except KeyError:
			print("[-]", "X-Content-Type-Options header not present", ':', "fail!")			

	def scan_xframe(self):
		"""X-Frame-Options should be set to DENY or SAMEORIGIN"""
		try:
			if "deny" in self.headers["X-Frame-Options"].lower():
				print("[+]", "X-Frame-Options", ':', "pass")
			elif "sameorigin" in self.headers["X-Frame-Options"].lower():
				print("[+]", "X-Frame-Options", ':', "pass")
			else:
				print("[-]", "X-Frame-Options header not set correctly", ':', "fail!")
		except KeyError:
			print("[-]", "X-Frame-Options header not present", ':', "fail!")

	def scan_hsts(self):
		"""config failure if HSTS header is not present"""
		try:
			if self.headers["Strict-Transport-Security"]:
				print("[+]", "Strict-Transport-Security", ':', "pass")
		except KeyError:
			print("[-]", "Strict-Transport-Security header not present", ':', "fail!")

	def scan_policy(self):
		"""config failure if Security Policy header is not present"""
		try:
			if self.headers["Content-Security-Policy"]:
				print("[+]", "Content-Security-Policy", ':', "pass")
		except KeyError:
			print("[-]", "Content-Security-Policy header not present", ':', "fail!")

	def scan_secure(self, cookie):
		"""Set-Cookie header should have the secure attribute set"""
		if cookie.secure:
			print("[+]", "Secure", ':', "pass")
		else:
			print("[-]", "Secure attribute not set", ':', "fail!")

	def scan_httponly(self, cookie):
		"""Set-Cookie header should have the HttpOnly attribute set"""
		if cookie.has_nonstandard_attr('httponly') or cookie.has_nonstandard_attr('HttpOnly'):
			print("[+]", "HttpOnly", ':', "pass")
		else:
			print("[-]", "HttpOnly attribute not set", ':', "fail!")

if __name__ == "__main__":

	target = ScanHeaders("http://localhost:8000/setup.php")

	for key in target.headers:
		print(key, ":", target.headers[key])

	print()

	target.scan_xxss()
	target.scan_nosniff()
	target.scan_xframe()
	target.scan_hsts()
	target.scan_policy()

	for cookie in target.cookies:
		print("Set-Cookie:")
		target.scan_secure(cookie)
		target.scan_httponly(cookie)	

