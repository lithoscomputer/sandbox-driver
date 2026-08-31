use async_trait::async_trait;
use sandbox_driver::{Result, ShellCommand};

use crate::exec::shell_quote;

/// Local Docker CLI access for one container sandbox.
pub(crate) struct DockerShellCommand {
    container_id: String,
    working_dir:  String,
}

impl DockerShellCommand {
    pub(crate) fn new(container_id: String, working_dir: String) -> Self {
        Self {
            container_id,
            working_dir,
        }
    }
}

#[async_trait]
impl ShellCommand for DockerShellCommand {
    async fn shell_command(&self) -> Result<String> {
        let shell = format!("cd {} && exec sh -l", shell_quote(&self.working_dir));
        Ok(format!(
            "docker exec -it {} sh -lc {}",
            shell_quote(&self.container_id),
            shell_quote(&shell)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shell_command_opens_a_login_shell_in_the_working_directory() {
        let access = DockerShellCommand::new(
            "fabro-run-01HY0000000000000000000000".to_owned(),
            "/workspace/rack-test".to_owned(),
        );

        assert_eq!(
            access.shell_command().await.expect("builds command"),
            "docker exec -it 'fabro-run-01HY0000000000000000000000' sh -lc \
             'cd '\\''/workspace/rack-test'\\'' && exec sh -l'"
        );
    }

    #[tokio::test]
    async fn shell_command_quotes_identifiers_and_directories() {
        let access = DockerShellCommand::new(
            "container with spaces".to_owned(),
            "/workspace/repo with spaces".to_owned(),
        );

        assert_eq!(
            access.shell_command().await.expect("builds command"),
            "docker exec -it 'container with spaces' sh -lc \
             'cd '\\''/workspace/repo with spaces'\\'' && exec sh -l'"
        );
    }
}
