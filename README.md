# SonarCloud Vulnerable Code Prospector for C (SVCP4C)

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

A tool that aims to collect vulnerable source code from open-source repositories linked to [SonarCloud](https://sonarcloud.io/) by using its [REST API](https://sonarcloud.io/web_api). The output consists of a set of tagged files suitable for extracting features and creating training datasets for Machine Learning algorithms. Vulnerabilities are listed in each file using comments appended at the end of each file. Such comments follow the format `// starting_line,starting_offset;ending_line,ending_offset` (with offset being the column). For example:

```c
//						↓↓↓VULNERABLE LINES↓↓↓

// 106,8;106,15

// 126,8;126,15

// 891,24;891,31

// 897,24;897,31

// 917,20;917,27
```

For a detailed explanation about SVCP4C, please check [this](https://doi.org/10.3390/app10041270) research paper. Also, sample datasets obtained with it are available in [this](https://github.com/uleroboticsgroup/SVCP4C) other repository.

# Usage

```bash
python SVCP4C.py <output_path> <optional_args>
```

By default, the tool runs in quiet mode.

## Arguments

Only the first argument (`output_path`) is required and it corresponds to the directory in which the tagged vulnerable source code will be downloaded into. The rest are optional:

| Argument | Description              |
| :------: | :----------------------- |
| -h       | Prints the usage message |
| -v       | Executes in verbose mode |

## Dependencies

Running SVCP4C requires the `requests` Python package, which may be installed using pip.

# Reference

For scientific publications, please reference SVCP4C using:

## Plain

```
Raducu, R., Esteban, G., Rodríguez Lera, F. J., & Fernández, C. (2020). Collecting Vulnerable Source Code from Open-Source Repositories for Dataset Generation. Applied Sciences, 10 (4), 1270. DOI: https://doi.org/10.3390/app10041270
```

## BibTeX

```BibTeX
@ARTICLE{Raducu2020,
  Title     = {Collecting Vulnerable Source Code from Open-Source Repositories for Dataset Generation},
  Author    = {Raducu, Razvan and Esteban, Gonzalo and Rodr{\'\i}guez Lera, Francisco Javier and Fern{\'a}ndez, Camino},
  Journal   = {Applied Sciences},
  Volume    = {10},
  Number    = {4},
  Pages     = {1270},
  Year      = {2020},
  Publisher = {Multidisciplinary Digital Publishing Institute},
  Doi       = {https://doi.org/10.3390/app10041270}
}
```

# License

SVCP4C is licensed under [GNU GPLv3](https://choosealicense.com/licenses/gpl-3.0/).