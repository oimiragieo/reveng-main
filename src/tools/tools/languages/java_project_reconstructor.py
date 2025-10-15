#!/usr/bin/env python3
"""
REVENG Java Project Reconstructor
==================================

Reconstructs original Maven/Gradle project structure from decompiled Java code.
Infers package structure, generates build files, organizes resources.

Features:
- Maven project structure generation (pom.xml)
- Gradle project structure generation (build.gradle)
- Package structure inference from class paths
- Resource extraction and organization
- Dependency analysis from imports
"""

import os
import json
import logging
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
import re

logger = logging.getLogger(__name__)


@dataclass
class JavaClass:
    """Represents a decompiled Java class"""
    name: str
    package: str
    full_name: str
    source_file: Path
    imports: List[str]
    extends: Optional[str]
    implements: List[str]
    is_interface: bool
    is_abstract: bool
    is_public: bool


@dataclass
class ProjectStructure:
    """Represents reconstructed project structure"""
    project_name: str
    group_id: str
    artifact_id: str
    version: str
    packages: List[str]
    dependencies: List[Dict[str, str]]
    main_class: Optional[str]
    resources: List[str]
    build_system: str  # 'maven' or 'gradle'


class JavaProjectReconstructor:
    """
    Reconstructs original Java project structure from decompiled code

    Workflow:
    1. Parse decompiled Java files
    2. Infer package structure
    3. Detect build system (Maven vs Gradle)
    4. Extract dependencies from imports
    5. Generate pom.xml or build.gradle
    6. Organize sources into src/main/java/
    7. Extract resources to src/main/resources/
    """

    def __init__(self, output_dir: str = "reconstructed_project"):
        self.output_dir = Path(output_dir)
        self.classes: List[JavaClass] = []
        self.packages: Set[str] = set()
        self.imports: Set[str] = set()
        self.main_classes: List[str] = []

        # Common Maven dependencies mapping (import -> dependency)
        self.dependency_map = {
            'org.springframework': {'groupId': 'org.springframework.boot', 'artifactId': 'spring-boot-starter', 'version': '2.7.0'},
            'org.hibernate': {'groupId': 'org.hibernate', 'artifactId': 'hibernate-core', 'version': '5.6.0'},
            'com.google.gson': {'groupId': 'com.google.code.gson', 'artifactId': 'gson', 'version': '2.10'},
            'org.apache.commons': {'groupId': 'org.apache.commons', 'artifactId': 'commons-lang3', 'version': '3.12.0'},
            'org.slf4j': {'groupId': 'org.slf4j', 'artifactId': 'slf4j-api', 'version': '1.7.36'},
            'com.fasterxml.jackson': {'groupId': 'com.fasterxml.jackson.core', 'artifactId': 'jackson-databind', 'version': '2.13.0'},
            'org.junit': {'groupId': 'org.junit.jupiter', 'artifactId': 'junit-jupiter', 'version': '5.8.2'},
            'org.mockito': {'groupId': 'org.mockito', 'artifactId': 'mockito-core', 'version': '4.6.0'},
        }

    def reconstruct_from_jar(self, jar_path: str, analysis_output: str) -> ProjectStructure:
        """
        Reconstruct project from JAR file and decompilation output

        Args:
            jar_path: Path to original JAR file
            analysis_output: Path to java_bytecode_analyzer output directory

        Returns:
            ProjectStructure with all project metadata
        """
        logger.info(f"Reconstructing project from {jar_path}")

        # 1. Parse decompiled Java files
        self._parse_decompiled_sources(analysis_output)

        # 2. Extract metadata from JAR manifest
        manifest_data = self._extract_jar_manifest(jar_path)

        # 3. Infer project metadata
        project_name = Path(jar_path).stem
        group_id = self._infer_group_id()
        artifact_id = project_name.lower().replace(' ', '-')
        version = manifest_data.get('Implementation-Version', '1.0.0')

        # 4. Detect build system (look for Maven/Gradle markers)
        build_system = self._detect_build_system(jar_path)

        # 5. Infer dependencies from imports
        dependencies = self._infer_dependencies()

        # 6. Find main class
        main_class = manifest_data.get('Main-Class') or self._find_main_class()

        # 7. Extract resources from JAR
        resources = self._extract_resources(jar_path)

        project = ProjectStructure(
            project_name=project_name,
            group_id=group_id,
            artifact_id=artifact_id,
            version=version,
            packages=sorted(self.packages),
            dependencies=dependencies,
            main_class=main_class,
            resources=resources,
            build_system=build_system
        )

        # 8. Generate project structure
        self._generate_project_structure(project, analysis_output)

        logger.info(f"Project reconstructed: {self.output_dir}")
        return project

    def _parse_decompiled_sources(self, analysis_output: str):
        """Parse decompiled Java source files"""
        analysis_path = Path(analysis_output)

        # Find decompiled sources directory
        decompiled_dir = analysis_path / 'decompiled'
        if not decompiled_dir.exists():
            logger.warning(f"Decompiled directory not found: {decompiled_dir}")
            return

        # Parse all .java files
        for java_file in decompiled_dir.rglob('*.java'):
            try:
                java_class = self._parse_java_file(java_file)
                if java_class:
                    self.classes.append(java_class)
                    self.packages.add(java_class.package)
                    self.imports.update(java_class.imports)
            except Exception as e:
                logger.warning(f"Failed to parse {java_file}: {e}")

    def _parse_java_file(self, java_file: Path) -> Optional[JavaClass]:
        """Parse a single Java file and extract metadata"""
        try:
            content = java_file.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            logger.warning(f"Failed to read {java_file}: {e}")
            return None

        # Extract package
        package_match = re.search(r'package\s+([\w.]+);', content)
        package = package_match.group(1) if package_match else ''

        # Extract class name
        class_match = re.search(r'(?:public\s+)?(?:abstract\s+)?(?:class|interface|enum)\s+(\w+)', content)
        if not class_match:
            return None
        class_name = class_match.group(1)

        # Extract imports
        imports = re.findall(r'import\s+([\w.]+(?:\.\*)?);\s*', content)

        # Extract extends
        extends_match = re.search(r'extends\s+([\w.<>]+)', content)
        extends = extends_match.group(1) if extends_match else None

        # Extract implements
        implements_match = re.search(r'implements\s+([\w.<>,\s]+)', content)
        implements = []
        if implements_match:
            implements = [impl.strip() for impl in implements_match.group(1).split(',')]

        # Detect type
        is_interface = 'interface ' + class_name in content
        is_abstract = 'abstract class ' + class_name in content
        is_public = 'public ' in content

        full_name = f"{package}.{class_name}" if package else class_name

        return JavaClass(
            name=class_name,
            package=package,
            full_name=full_name,
            source_file=java_file,
            imports=imports,
            extends=extends,
            implements=implements,
            is_interface=is_interface,
            is_abstract=is_abstract,
            is_public=is_public
        )

    def _extract_jar_manifest(self, jar_path: str) -> Dict[str, str]:
        """Extract metadata from JAR manifest"""
        manifest_data = {}

        try:
            with zipfile.ZipFile(jar_path, 'r') as jar:
                if 'META-INF/MANIFEST.MF' in jar.namelist():
                    manifest_content = jar.read('META-INF/MANIFEST.MF').decode('utf-8', errors='ignore')

                    for line in manifest_content.splitlines():
                        if ':' in line:
                            key, value = line.split(':', 1)
                            manifest_data[key.strip()] = value.strip()
        except Exception as e:
            logger.warning(f"Failed to extract manifest from {jar_path}: {e}")

        return manifest_data

    def _infer_group_id(self) -> str:
        """Infer Maven group ID from package structure"""
        if not self.packages:
            return 'com.example'

        # Find common package prefix
        package_list = sorted(self.packages)
        if len(package_list) == 1:
            parts = package_list[0].split('.')
            return '.'.join(parts[:2]) if len(parts) >= 2 else parts[0]

        # Find longest common prefix
        common_prefix = package_list[0]
        for pkg in package_list[1:]:
            while not pkg.startswith(common_prefix):
                common_prefix = '.'.join(common_prefix.split('.')[:-1])
                if not common_prefix:
                    return 'com.example'

        return common_prefix or 'com.example'

    def _detect_build_system(self, jar_path: str) -> str:
        """Detect original build system (Maven vs Gradle)"""
        try:
            with zipfile.ZipFile(jar_path, 'r') as jar:
                filelist = jar.namelist()

                # Look for Maven markers
                if any('maven' in f.lower() for f in filelist):
                    return 'maven'

                # Look for Gradle markers
                if any('gradle' in f.lower() for f in filelist):
                    return 'gradle'

                # Check for pom.properties
                if 'META-INF/maven/' in ' '.join(filelist):
                    return 'maven'
        except Exception as e:
            logger.warning(f"Failed to detect build system: {e}")

        # Default to Maven (more common)
        return 'maven'

    def _infer_dependencies(self) -> List[Dict[str, str]]:
        """Infer Maven dependencies from imports"""
        dependencies = []
        seen_artifacts = set()

        for import_stmt in self.imports:
            # Skip java.* and javax.* (built-in)
            if import_stmt.startswith(('java.', 'javax.')):
                continue

            # Try to match to known dependencies
            for prefix, dep_info in self.dependency_map.items():
                if import_stmt.startswith(prefix):
                    artifact = dep_info['artifactId']
                    if artifact not in seen_artifacts:
                        dependencies.append(dep_info.copy())
                        seen_artifacts.add(artifact)
                    break

        return dependencies

    def _find_main_class(self) -> Optional[str]:
        """Find main class by looking for public static void main"""
        for java_class in self.classes:
            try:
                content = java_class.source_file.read_text(encoding='utf-8', errors='ignore')
                if 'public static void main(String[]' in content or 'public static void main(String ...' in content:
                    return java_class.full_name
            except Exception:
                continue

        return None

    def _extract_resources(self, jar_path: str) -> List[str]:
        """Extract resource files from JAR"""
        resources = []

        try:
            with zipfile.ZipFile(jar_path, 'r') as jar:
                for file_info in jar.filelist:
                    filename = file_info.filename

                    # Skip .class files and META-INF
                    if filename.endswith('.class') or filename.startswith('META-INF/'):
                        continue

                    # Skip directories
                    if filename.endswith('/'):
                        continue

                    resources.append(filename)
        except Exception as e:
            logger.warning(f"Failed to extract resources: {e}")

        return resources

    def _generate_project_structure(self, project: ProjectStructure, analysis_output: str):
        """Generate Maven/Gradle project structure on disk"""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Create standard directory structure
        src_main_java = self.output_dir / 'src' / 'main' / 'java'
        src_main_resources = self.output_dir / 'src' / 'main' / 'resources'
        src_test_java = self.output_dir / 'src' / 'test' / 'java'

        src_main_java.mkdir(parents=True, exist_ok=True)
        src_main_resources.mkdir(parents=True, exist_ok=True)
        src_test_java.mkdir(parents=True, exist_ok=True)

        # Copy decompiled sources to src/main/java with proper package structure
        self._organize_sources(src_main_java, analysis_output)

        # Generate build file
        if project.build_system == 'maven':
            self._generate_pom_xml(project)
        else:
            self._generate_build_gradle(project)

        # Generate README
        self._generate_readme(project)

        # Save project metadata
        metadata_file = self.output_dir / 'project_metadata.json'
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(asdict(project), f, indent=2)

        logger.info(f"Generated project structure in {self.output_dir}")

    def _organize_sources(self, src_main_java: Path, analysis_output: str):
        """Organize decompiled sources into proper package structure"""
        analysis_path = Path(analysis_output)
        decompiled_dir = analysis_path / 'decompiled'

        if not decompiled_dir.exists():
            logger.warning("No decompiled sources found")
            return

        # Copy each class to proper package directory
        for java_class in self.classes:
            # Create package directory
            package_path = src_main_java / java_class.package.replace('.', os.sep)
            package_path.mkdir(parents=True, exist_ok=True)

            # Copy source file
            dest_file = package_path / f"{java_class.name}.java"
            try:
                import shutil
                shutil.copy2(java_class.source_file, dest_file)
            except Exception as e:
                logger.warning(f"Failed to copy {java_class.source_file}: {e}")

    def _generate_pom_xml(self, project: ProjectStructure):
        """Generate Maven pom.xml"""
        pom_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
                             http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>{project.group_id}</groupId>
    <artifactId>{project.artifact_id}</artifactId>
    <version>{project.version}</version>
    <packaging>jar</packaging>

    <name>{project.project_name}</name>
    <description>Reconstructed project from reverse engineering</description>

    <properties>
        <maven.compiler.source>11</maven.compiler.source>
        <maven.compiler.target>11</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>

    <dependencies>
'''

        # Add dependencies
        for dep in project.dependencies:
            pom_content += f'''        <dependency>
            <groupId>{dep['groupId']}</groupId>
            <artifactId>{dep['artifactId']}</artifactId>
            <version>{dep['version']}</version>
        </dependency>
'''

        pom_content += '''    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.11.0</version>
            </plugin>
'''

        # Add main class if found
        if project.main_class:
            pom_content += f'''            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-jar-plugin</artifactId>
                <version>3.3.0</version>
                <configuration>
                    <archive>
                        <manifest>
                            <mainClass>{project.main_class}</mainClass>
                        </manifest>
                    </archive>
                </configuration>
            </plugin>
'''

        pom_content += '''        </plugins>
    </build>
</project>
'''

        pom_file = self.output_dir / 'pom.xml'
        with open(pom_file, 'w', encoding='utf-8') as f:
            f.write(pom_content)

        logger.info(f"Generated pom.xml at {pom_file}")

    def _generate_build_gradle(self, project: ProjectStructure):
        """Generate Gradle build.gradle"""
        gradle_content = f'''plugins {{
    id 'java'
    id 'application'
}}

group = '{project.group_id}'
version = '{project.version}'

sourceCompatibility = '11'
targetCompatibility = '11'

repositories {{
    mavenCentral()
}}

dependencies {{
'''

        # Add dependencies
        for dep in project.dependencies:
            gradle_content += f"    implementation '{dep['groupId']}:{dep['artifactId']}:{dep['version']}'\n"

        gradle_content += '''}

'''

        # Add main class if found
        if project.main_class:
            gradle_content += f'''application {{
    mainClass = '{project.main_class}'
}}

'''

        gradle_content += '''tasks.withType(JavaCompile) {
    options.encoding = 'UTF-8'
}
'''

        build_file = self.output_dir / 'build.gradle'
        with open(build_file, 'w', encoding='utf-8') as f:
            f.write(gradle_content)

        logger.info(f"Generated build.gradle at {build_file}")

    def _generate_readme(self, project: ProjectStructure):
        """Generate project README"""
        readme_content = f'''# {project.project_name}

**Version**: {project.version}
**Group ID**: {project.group_id}
**Artifact ID**: {project.artifact_id}
**Build System**: {project.build_system.capitalize()}

## About

This project was reconstructed from a compiled JAR file using REVENG reverse engineering toolkit.

## Project Structure

```
{project.artifact_id}/
├── src/
│   ├── main/
│   │   ├── java/          # Decompiled Java sources
│   │   └── resources/     # Extracted resources
│   └── test/
│       └── java/          # Test sources
├── {"pom.xml" if project.build_system == "maven" else "build.gradle"}
└── README.md
```

## Build Instructions

### Maven
```bash
mvn clean compile
mvn package
'''

        if project.main_class:
            readme_content += f'mvn exec:java -Dexec.mainClass="{project.main_class}"\n'

        readme_content += '''```

### Gradle
```bash
gradle clean build
gradle jar
'''

        if project.main_class:
            readme_content += 'gradle run\n'

        readme_content += f'''```

## Detected Packages

{chr(10).join(f'- {pkg}' for pkg in sorted(project.packages))}

## Dependencies

{chr(10).join(f'- {dep["groupId"]}:{dep["artifactId"]}:{dep["version"]}' for dep in project.dependencies)}
'''

        if project.main_class:
            readme_content += f'''
## Main Class

`{project.main_class}`
'''

        readme_content += '''
## Notes

- This is a reconstructed project from decompiled bytecode
- Some code may not compile perfectly due to decompilation limitations
- Original comments and formatting are lost during compilation
- Some dependencies may need version adjustments

## Generated by REVENG

[REVENG Reverse Engineering Toolkit](https://github.com/yourusername/reveng)
'''

        readme_file = self.output_dir / 'README.md'
        with open(readme_file, 'w', encoding='utf-8') as f:
            f.write(readme_content)

        logger.info(f"Generated README.md at {readme_file}")


def main():
    """CLI interface for project reconstruction"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Reconstruct Maven/Gradle project from decompiled Java code'
    )
    parser.add_argument('jar_file', help='Path to JAR file')
    parser.add_argument('analysis_output', help='Path to java_bytecode_analyzer output directory')
    parser.add_argument('-o', '--output', default='reconstructed_project',
                       help='Output directory for reconstructed project')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Run reconstruction
    reconstructor = JavaProjectReconstructor(output_dir=args.output)
    project = reconstructor.reconstruct_from_jar(args.jar_file, args.analysis_output)

    print("\n" + "="*60)
    print("PROJECT RECONSTRUCTION COMPLETE")
    print("="*60)
    print(f"Project Name: {project.project_name}")
    print(f"Group ID: {project.group_id}")
    print(f"Artifact ID: {project.artifact_id}")
    print(f"Version: {project.version}")
    print(f"Build System: {project.build_system.capitalize()}")
    print(f"Packages: {len(project.packages)}")
    print(f"Dependencies: {len(project.dependencies)}")
    print(f"Main Class: {project.main_class or 'Not found'}")
    print(f"\nOutput: {args.output}")
    print("="*60)


if __name__ == '__main__':
    main()
