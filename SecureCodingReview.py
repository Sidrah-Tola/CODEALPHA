class SecureCodingReviewTool:
    def __init__(self):
        self.checklist = {
            "Input Validation": self.input_validation,
            "Authentication & Authorization": self.authentication_authorization,
            "Error Handling": self.error_handling,
            "Data Protection": self.data_protection,
            "Secure Communication": self.secure_communication,
            "Secure APIs": self.secure_apis,
            "Session Management": self.session_management,
            "Code Quality": self.code_quality,
            "Logging and Monitoring": self.logging_monitoring,
            "Dependency Management": self.dependency_management,
            "Security Misconfiguration": self.security_misconfiguration,
            "Cross-Site Scripting (XSS)": self.xss,
            "Cross-Site Request Forgery (CSRF)": self.csrf,
            "SQL Injection": self.sql_injection,
        }
        self.findings = []
        self.code_snippet = ""

    def input_code_snippet(self):
        print("Please enter the code snippet you want to review:")
        self.code_snippet = input("Code Snippet:\n")
        print("\nCode snippet received for review.\n")

    def input_validation(self):
        print("### Input Validation ###")
        print("Does the code validate all user inputs? (yes/no)")
        response = input().strip().lower()
        if response == 'no':
            self.add_finding("Input validation is missing or insufficient.")
    
    def authentication_authorization(self):
        print("### Authentication & Authorization ###")
        print("Is there a strong password policy? (yes/no)")
        response = input().strip().lower()
        if response == 'no':
            self.add_finding("Weak password policy found.")
    
    def error_handling(self):
        print("### Error Handling ###")
        print("Are error messages user-friendly and do not expose sensitive information? (yes/no)")
        response = input().strip().lower()
        if response == 'no':
            self.add_finding("Error messages may expose sensitive information.")
    
    def data_protection(self):
        print("### Data Protection ###")
        print("Is sensitive data encrypted at rest and in transit? (yes/no)")
        response = input().strip().lower()
        if response == 'no':
            self.add_finding("Sensitive data is not properly encrypted.")
    
    def secure_communication(self):
        print("### Secure Communication ###")
        print("Is HTTPS used for all communication? (yes/no)")
        response = input().strip().lower()
        if response == 'no':
            self.add_finding("Communication is not secured with HTTPS.")
    
    def secure_apis(self):
        print("### Secure APIs ###")
        print("Are APIs properly authenticated and authorized? (yes/no)")
        response = input().strip().lower()
        if response == 'no':
            self.add_finding("APIs lack proper authentication and authorization.")
    
    def session_management(self):
        print("### Session Management ###")
        print("Are secure cookies used? (yes/no)")
        response = input().strip().lower()
        if response == 'no':
            self.add_finding("Cookies are not secure.")
    
    def code_quality(self):
        print("### Code Quality ###")
        print("Are hardcoded secrets avoided in the code? (yes/no)")
        response = input().strip().lower()
        if response == 'no':
            self.add_finding("Hardcoded secrets are found in the code.")
    
    def logging_monitoring(self):
        print("### Logging and Monitoring ###")
        print("Is there adequate logging for security-related events? (yes/no)")
        response = input().strip().lower()
        if response == 'no':
            self.add_finding("Inadequate logging for security-related events.")
    
    def dependency_management(self):
        print("### Dependency Management ###")
        print("Are all dependencies up-to-date and scanned for vulnerabilities? (yes/no)")
        response = input().strip().lower()
        if response == 'no':
            self.add_finding("Dependencies are outdated or not scanned.")
    
    def security_misconfiguration(self):
        print("### Security Misconfiguration ###")
        print("Are security configurations validated? (yes/no)")
        response = input().strip().lower()
        if response == 'no':
            self.add_finding("Security configurations are not validated.")
    
    def xss(self):
        print("### Cross-Site Scripting (XSS) ###")
        print("Is output properly encoded to prevent XSS? (yes/no)")
        response = input().strip().lower()
        if response == 'no':
            self.add_finding("Output is not properly encoded.")
    
    def csrf(self):
        print("### Cross-Site Request Forgery (CSRF) ###")
        print("Is CSRF protection implemented? (yes/no)")
        response = input().strip().lower()
        if response == 'no':
            self.add_finding("CSRF protection is not implemented.")
    
    def sql_injection(self):
        print("### SQL Injection ###")
        print("Are parameterized queries used to prevent SQL injection? (yes/no)")
        response = input().strip().lower()
        if response == 'no':
            self.add_finding("Non-parameterized queries are found.")
    
    def add_finding(self, description):
        """Add a finding to the review."""
        self.findings.append(description)
        print("Finding added:", description)

    def generate_report(self):
        """Generate a summary report of the review."""
        print("\nSecure Coding Review Report")
        print("============================")
        print("Code Snippet Reviewed:\n", self.code_snippet)
        if self.findings:
            print("\nFindings:")
            for idx, finding in enumerate(self.findings, start=1):
                print(f"{idx}. {finding}")
        else:
            print("No findings reported.")

# Example usage:
if __name__ == "__main__":
    review_tool = SecureCodingReviewTool()
    
    # Input the code snippet to be reviewed
    review_tool.input_code_snippet()
    
    # Conduct the review by going through each category
    for category in review_tool.checklist.keys():
        review_tool.checklist[category]()

    # Generate the report
    review_tool.generate_report()
