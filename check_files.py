import os

print("Current folder:", os.getcwd())

files = [
    "templates/home.html",
    "templates/register.html",
    "templates/login.html",
    "templates/dashboard.html",
    "templates/modules.html",
    "templates/lesson.html",
    "templates/quiz.html",
    "templates/results.html",
    "templates/progress.html",
    "templates/admin_login.html",
    "templates/admin_dashboard.html",
    "static/style.css",
    "database.py"
]

for file in files:
    print("FOUND" if os.path.isfile(file) else "MISSING", file)