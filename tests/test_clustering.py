from greedybear.cronjobs.commands.cluster import tokenize

from . import CustomTestCase


class TokenizeTestCase(CustomTestCase):
    def test_tokenize_basic(self):
        """Test basic tokenization of simple commands - just a dummy cahnge to trigger CI"""
        input_seq = ["ls -l", "cd /home"]
        expected = ["ls", "-l", "cd", "/home"]
        self.assertEqual(tokenize(input_seq), expected)

    def test_tokenize_empty(self):
        """Test tokenization of empty sequences and strings"""
        self.assertEqual(tokenize([]), [])
        self.assertEqual(tokenize([""]), [])
        self.assertEqual(tokenize([" "]), [])
        self.assertEqual(tokenize(["", ""]), [])

    def test_tokenize_semicolons(self):
        """Test handling of semicolons in commands"""
        input_seq = ["ls -l;cd /home", "echo hello;pwd"]
        expected = ["ls", "-l", "cd", "/home", "echo", "hello", "pwd"]
        self.assertEqual(tokenize(input_seq), expected)

    def test_tokenize_multiple_spaces(self):
        """Test handling of multiple whitespace characters"""
        input_seq = ["ls   -l", "cd    /home"]
        expected = ["ls", "-l", "cd", "/home"]
        self.assertEqual(tokenize(input_seq), expected)

    def test_tokenize_mixed_delimiters(self):
        """Test handling of mixed semicolons and spaces"""
        input_seq = ["ls -l;  cd /home;pwd", "echo   hello ; ls"]
        expected = ["ls", "-l", "cd", "/home", "pwd", "echo", "hello", "ls"]
        self.assertEqual(tokenize(input_seq), expected)

    def test_tokenize_special_characters(self):
        """Test handling of special characters and paths"""
        input_seq = ["ls /usr/bin", "cd ../home", "echo $PATH"]
        expected = ["ls", "/usr/bin", "cd", "../home", "echo", "$PATH"]
        self.assertEqual(tokenize(input_seq), expected)

    def test_tokenize_quotes(self):
        """Test behavior with quoted strings (note: quotes are not preserved)"""
        input_seq = ['echo "hello world"', "ls 'Documents'"]
        expected = ["echo", '"hello', 'world"', "ls", "'Documents'"]
        self.assertEqual(tokenize(input_seq), expected)

    def test_tokenize_edge_cases(self):
        """Test edge cases with unusual inputs"""
        input_seq = [
            ";;;;;",  # Multiple semicolons
            "  ;  ;  ",  # Semicolons with spaces
            "\t\n",  # Special whitespace
            "cmd1;;cmd2",  # Multiple semicolons between commands
        ]
        expected = ["cmd1", "cmd2"]
        self.assertEqual(tokenize(input_seq), expected)

    def test_tokenize_mixed_content(self):
        """Test mixture of various command patterns"""
        input_seq = [
            "ls -l;cd /home;pwd",
            "echo hello   world",
            ";",
            "git commit -m 'update'",
        ]
        expected = [
            "ls",
            "-l",
            "cd",
            "/home",
            "pwd",
            "echo",
            "hello",
            "world",
            "git",
            "commit",
            "-m",
            "'update'",
        ]
        self.assertEqual(tokenize(input_seq), expected)
