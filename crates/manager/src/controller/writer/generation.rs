use super::*;
impl Controller {
    pub(crate) fn generate_missing_password(
        &mut self,
        path: &str,
        kind: GenerateKind,
    ) -> Result<(), String> {
        let parsed = SecretPath::parse(path).map_err(|error| error.to_string())?;
        let leaf = self
            .schema
            .leaf(&parsed)
            .map_err(|error| error.to_string())?;
        let (value_type, constraints, ids, keys, external_input_required) = match leaf {
            LeafSpec::Stored(spec) => (
                spec.value_type,
                spec.consumer_constraints,
                spec.recipient_ids,
                spec.recipient_public_keys,
                spec.external_input_required,
            ),
            LeafSpec::Generated(spec) => (
                spec.value_type,
                spec.consumer_constraints,
                spec.recipient_ids,
                spec.recipient_public_keys,
                spec.external_input_required,
            ),
            LeafSpec::Operator(_) => {
                return Err("operator keys are generated with their declared generator".into())
            }
        };
        if external_input_required {
            return Err("this value must be supplied from the external system".into());
        }
        if value_type != Some(ValueType::Password) {
            return Err("not a password leaf".into());
        }
        let value = generate_compatible(kind, constraints.as_ref())?;
        let recipients = ids
            .iter()
            .zip(keys.iter())
            .map(|(id, key)| Recipient {
                id,
                ssh_public_key: key,
            })
            .collect::<Vec<_>>();
        self.client
            .set_if_version(&parsed, &value, &recipients, &self.provider, None)
            .map_err(|error| error.to_string())
    }
}
