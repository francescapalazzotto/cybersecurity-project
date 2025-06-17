import Col from 'react-bootstrap/esm/Col';
import Form from 'react-bootstrap/Form';

function FormDecrypt({
    stateDecrypt,
    onChange,
}) {
  return (
    <Form>
      <Form.Group className="mb-3">
        <Form.Label>
          Carica File
        </Form.Label>
        <Form.Control
          type="file"
          name='file'
          onChange={(event) => onChange('decrypt', event)}
          />
        <Form.Label>
          Inserisci Dati Associati
        </Form.Label>
        <Form.Control
          type='text'
          name='associated_data'
          value={stateDecrypt?.associated_data}
          onChange={(event) => onChange('decrypt', event)}
        />
        <Form.Label>
          Scegli Modalità di Criptazione
        </Form.Label>
        <Form.Select
          name='mode'
          placeholder='Seleziona una modalità'
          onChange={(selOption) => onChange('decrypt', selOption )}
        >
          <option value="" disabled>Seleziona una modalità</option>
          <option value="gcm">Galois/Counter Mode (GCM) </option>
          <option value="etm">Encrypt-then-MAC (EtM)</option>
        </Form.Select>
        <Form.Label>
          Inserisci Password
        </Form.Label>
        <Col sm="10">
          <Form.Control
            type="password"
            name="password"
            placeholder="Password"
            value={stateDecrypt.password || ''}
            onChange={(event) => onChange('decrypt', event)}
          />
        </Col>
      </Form.Group>
    </Form>
  );
}

export default FormDecrypt;