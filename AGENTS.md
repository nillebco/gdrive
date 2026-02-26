# AGENTS

This software is about managing (uploading and exporting) files to/from Google Drive.

This software has two implementations - the python one and the nodeJS one.

Always consider the README.md before starting new implementations, and update it when you're done changing the code.

Add commands to the `cli` file if needed

Write at least one unit test to verify the code you implemented.

Update the README.md file with the necessary instructions (when they can serve as documentation)

./cli pre-commit or ./cli lint are your friend

A function does only one thing: catching an exception is one thing.

## Python-specific instructions

Use uv to manage dependencies (uv add nameofthedependencies)

Use uv run to execute python code.

Use typing everywhere and verify using ty.

Run the tests using `./cli test`.

Avoid broad exception handlers: avoid putting a global try-except and then spaghetti code in the try section. It's worth a separate function.
