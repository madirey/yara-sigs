type.inbound
and any(attachments,
		.file_extension in $archive_extensions and
		any(beta.binexplode(.), length(.scan.yara.matches) > 0)
)
//first-time sender
and (
			(
				sender.email.domain.root_domain in $free_email_providers
				and sender.email.email not in $sender_emails
			)
			or (
				sender.email.domain.root_domain not in $free_email_providers
				and sender.email.domain.domain not in $sender_emails
			)
)
