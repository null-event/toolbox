var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /private/tmp/touched.txt");
app.doShellScript("echo "111" >> /Users/nullevent/.zshrc");
