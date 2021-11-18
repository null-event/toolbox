#!/usr/bin/python3
import sys
from pdfminer.high_level import extract_text

print("Usage: python3 script.py <pdfname_in_pwd> <keyword>")
print("Example: python3 extract_pdf_key_terms.py '2020-01-02-upload.pdf' 'dolore'")
print("\n")
file = [sys.argv[1]]
keywords = sys.argv[2]

for i in file:
	text = extract_text(i)
	if(keywords in text):
		print ("Found in: "+i)
		print("\n")
		print (text)
