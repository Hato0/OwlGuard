<div id="top"></div>


<br />
<div align="center">
    <a href="https://github.com/Hato0/OwlGuard">
    <img src="OwlGuard/OwlGuardWebsite/OwlGuardWebsite/static/img/logo.png" alt="Logo" width=10%>
  </a>

<h3 align="center">OwlGuard</h3>

  <p align="center">
    Rule Management Platform designed for multi-instance management.
    <br />
        <a href="https://github.com/Hato0/OwlGuard"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/Hato0/OwlGuard/issues">Report Bug</a>
    ·
    <a href="https://github.com/Hato0/OwlGuard/issues">Request Feature</a>
  </p>
</div>

## About The Project

OwlGuard is a platform designed to provide security teams a better way to manage SIEM rules. They can be imported directly from a SIEM by a simple connection or using SIGMA format and YAML files. 
All the actions (modification, retiring, documentations, testing scripts, ...) can be manage on the platform and are logs with an history keep to audit the changes. This tool aim to rapidely onboard clients just by using already developed rules and a simple connection to their SIEM. For now only SPLUNK is supported, if the project get interest other SIEM will be included in the support list. 


## Getting Started

You can clone or fork this repository to start using it. 

### Prerequisites

Some python module are necessary to run it :
```sh
pip install -r OwlGuardWebsite/requirements.txt
```

For some reasons, depending on the deployed environment you will need to manually add the backend in [sigmac](https://sigmahq.io/docs/digging-deeper/backends):
```sh
pip3 install sigma-cli
sigma plugin install splunk
```
Thanks creators for this tool.

### Installation

Clone this github repository and start using it !
```bash
git clone https://github.com/Hato0/OwlGuard.git
```

## Usage

To use this software you will need first to configure your config file (settings.py in OwlGuardWebsite/).  
This config file allow you to configure your database parameters.

Once this configuration file is setup for your need, launch the app.
To do so, nothing hard:
```bash
cd OwlGuardWebsite
python .\manage.py makemigrations
python .\manage.py migrate
python .\manage.py runserver
```

/!\ Only this command in test environments, to deploy the application in a production environment please follow the official Django [documentation](https://docs.djangoproject.com/en/5.0/howto/deployment/).

## Roadmap

- Rules
  - [X] Import YAML
  - [X] Versioning (comparaison between version possible inside the tool directly)
  - [X] Edit SIEM or SIGMA language directly in the tool
  - [X] Automatic creation of rules inside the SIEM
  - [X] Automatic updates (bidirectionnal)
- Connectors
  - [X] Create connector to multiple SIEM at once
  - [X] Manage which rules are associated with which connector
  - [X] Manage the status (enable/disable) of rules connectors by connectors easily
- Documentation
  - [X] Provide a documentation directly in the platform (addition and modification possible)
  - [X] Versioning (comparaison between version possible inside the tool directly)
  - [X] Associate the documentation with multiple rules
- Testing scripts
  - [X] Provide a way to manage testing scripts directly in the platform (addition and modification possible)
  - [X] Versioning (comparaison between version possible inside the tool directly)
  - [X] Associate the documentation with multiple rules
  - [ ] Launch directly from the platform and get result in real time (Caldera model)

See the [open issues](https://github.com/Hato0/OwlGuard) for a full list of proposed features (and known issues).

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/YourFeatureName`)
3. Commit your Changes (`git commit -m 'Add some YourFeatureName'`)
4. Push to the Branch (`git push origin feature/YourFeatureName`)
5. Open a Pull Request


## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

## Contact

hato0 - hato0@protonmail.ch

Project Link: [https://github.com/Hato0/OwlGuard](https://github.com/Hato0/OwlGuard)

<p align="right">(<a href="#top">back to top</a>)</p>

