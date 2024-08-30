import unittest

from django.test import tag

try:
    from .source import MyTestClass
except ImportError:
    from source import MyTestClass


class MyTestClassTestCase(unittest.TestCase):
    def test_my_first_element(self):
        my_class = MyTestClass()
        self.assertEqual(my_class.my_first_element(), 1)

    @tag("main")
    def test_my_third_element(self):
        my_class = MyTestClass()
        self.assertEqual(my_class.third_element, 3)

    @tag("manual")
    def test_my_second_element(self):
        my_class = MyTestClass()
        self.assertEqual(my_class.second_element, 2)


class TestB(unittest.TestCase):
    def test_add_task(self):
        from python_test.celery import add

        rst = add.apply(args=(4, 4)).get()
        self.assertEqual(rst, 8)
