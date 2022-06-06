# Branch Protection Automation


## Description

This project allows for automatic protection of repositories created within an organization.  Upon the creation of a new repository, a webhook event triggers an update to create a branch protection rule on the default branch of the repository.  The branch is protected, by default with the following options:
Pull Request and 1 Code review required to merge changes
Administrators must follow all rules

Changes can be made to the source code to update the protections added. 

## Requirements

1. A GitHub App with webhooks configured for the repository creation events.  If you are unfamiliar with how to use GitHub Apps, check out [this](https://docs.github.com/en/developers/apps/building-github-apps) tutorial.
2. A webserver is required to leverage this application.  If you are in need of such environment, check [here](https://docs.github.com/en/developers/apps/getting-started-with-apps/setting-up-your-development-environment-to-create-a-github-app) for how to setup a quick pre-production environment. Please note, you will need to use the files from this project to start this server (See installation below).   

## Installation
Once all requirements listed above are met install and configure the project.

1. Clone the repository to your local machine: 
`git clone https://github.com/ellisd-github-technical/branch_protection.git`
2. Configure the .env file.  There is an env-template file in the cloned repository to help you get started.  All of the details in this file will come from the creation of your app in step 1 of the requirements.  
3. Start and validate your server. 

## Troubleshooting
If you are having issues, please ensure that you have followed the steps in the Requirements to create your GitHub App and webserver. Troubleshooting steps can be found in the ["Setting up your development environment to create a GitHub App"](https://docs.github.com/en/developers/apps/getting-started-with-apps/setting-up-your-development-environment-to-create-a-github-app#troubleshooting) guide.  For all other technical issues, please open an [issue](https://github.com/ellisd-github-technical/branch_protection/issues/new). 

## Contributing Projects
This project would not be possible without the following resources:
1. [Using the GitHub API in your App](https://github.com/github-developer/using-the-github-api-in-your-app)
2. [Setting up your development environment to create a GitHub App](https://docs.github.com/en/developers/apps/getting-started-with-apps/setting-up-your-development-environment-to-create-a-github-app#troubleshooting)
3. [Building GitHub Apps](https://docs.github.com/en/developers/apps/building-github-apps)
4. [Octokit: Repository Modules](http://octokit.github.io/octokit.rb/Octokit/Client/Repositories.html)
