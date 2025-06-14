import Col from 'react-bootstrap/esm/Col';
import Form from 'react-bootstrap/Form';

function FormEncrypt({
    stateEncrypt,
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
            onChange={(event) => onChange('encrypt', event)}
            />
        <Form.Label>
            Scegli Modalità di Criptazione
        </Form.Label>
        <Form.Select
            name='mode'
            placeholder='Seleziona una modalità'
            onChange={(selOption) => onChange('encrypt', selOption )}
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
            value={stateEncrypt.password || ''}
            onChange={(event) => onChange('encrypt', event)}
          />
        </Col>
      </Form.Group>
    </Form>
  );
}

export default FormEncrypt;