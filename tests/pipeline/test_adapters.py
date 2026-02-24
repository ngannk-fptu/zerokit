"""
Tests for language adapters
"""
import unittest
import os
import sys
import tempfile
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../.agent')))

from pipeline.adapters.java_adapter import JavaAdapter
from pipeline.adapters.javascript_adapter import JavaScriptAdapter
from pipeline.adapters.go_adapter import GoAdapter

class TestJavaAdapter(unittest.TestCase):
    def test_maven_detection(self):
        """Test Maven project detection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create fake pom.xml
            pom_path = os.path.join(tmpdir, "pom.xml")
            with open(pom_path, "w") as f:
                f.write("<project></project>")
            
            adapter = JavaAdapter(tmpdir)
            self.assertEqual(adapter.build_system, "maven")
            print("✓ Maven detection works")
    
    def test_gradle_detection(self):
        """Test Gradle project detection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create fake build.gradle
            build_path = os.path.join(tmpdir, "build.gradle")
            with open(build_path, "w") as f:
                f.write("plugins { }")
            
            adapter = JavaAdapter(tmpdir)
            self.assertEqual(adapter.build_system, "gradle")
            print("✓ Gradle detection works")
    
    @unittest.skip("Requires Maven/Gradle and Java project")
    def test_health_check(self):
        """Integration test: health check."""
        pass

class TestJavaScriptAdapter(unittest.TestCase):
    def test_npm_detection(self):
        """Test npm project detection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create fake package.json
            pkg_path = os.path.join(tmpdir, "package.json")
            with open(pkg_path, "w") as f:
                json.dump({"name": "test", "version": "1.0.0"}, f)
            
            adapter = JavaScriptAdapter(tmpdir)
            self.assertEqual(adapter.package_manager, "npm")
            self.assertEqual(adapter.package_json["name"], "test")
            print("✓ npm detection works")
    
    def test_yarn_detection(self):
        """Test yarn project detection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create fake package.json and yarn.lock
            pkg_path = os.path.join(tmpdir, "package.json")
            with open(pkg_path, "w") as f:
                json.dump({"name": "test"}, f)
            
            yarn_lock = os.path.join(tmpdir, "yarn.lock")
            with open(yarn_lock, "w") as f:
                f.write("# yarn lockfile v1")
            
            adapter = JavaScriptAdapter(tmpdir)
            self.assertEqual(adapter.package_manager, "yarn")
            print("✓ yarn detection works")
    
    @unittest.skip("Requires npm/yarn and Node project")
    def test_health_check(self):
        """Integration test: health check."""
        pass

class TestGoAdapter(unittest.TestCase):
    def test_go_mod_detection(self):
        """Test go.mod detection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create fake go.mod
            mod_path = os.path.join(tmpdir, "go.mod")
            with open(mod_path, "w") as f:
                f.write("module example.com/test\n\ngo 1.21\n")
            
            adapter = GoAdapter(tmpdir)
            self.assertTrue(adapter.has_go_mod)
            print("✓ go.mod detection works")
    
    @unittest.skip("Requires Go and go.mod project")
    def test_health_check(self):
        """Integration test: health check."""
        pass

class TestCAdapter(unittest.TestCase):
    def test_cmake_detection(self):
        """Test CMake project detection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create fake CMakeLists.txt
            cmake_path = os.path.join(tmpdir, "CMakeLists.txt")
            with open(cmake_path, "w") as f:
                f.write("cmake_minimum_required(VERSION 3.10)\nproject(test)\n")
            
            from pipeline.adapters.c_adapter import CAdapter
            adapter = CAdapter(tmpdir)
            self.assertEqual(adapter.build_system, "cmake")
            print("✓ CMake detection works")
    
    def test_makefile_detection(self):
        """Test Makefile detection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create fake Makefile
            makefile_path = os.path.join(tmpdir, "Makefile")
            with open(makefile_path, "w") as f:
                f.write("all:\n\tgcc main.c -o app\n")
            
            from pipeline.adapters.c_adapter import CAdapter
            adapter = CAdapter(tmpdir)
            self.assertEqual(adapter.build_system, "make")
            print("✓ Makefile detection works")
    
    @unittest.skip("Requires CMake/Make and C++ project")
    def test_health_check(self):
        """Integration test: health check."""
        pass

if __name__ == '__main__':
    unittest.main()
