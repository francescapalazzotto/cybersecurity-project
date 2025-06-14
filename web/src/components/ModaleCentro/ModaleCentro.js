import Button from 'react-bootstrap/Button';
import Modal from 'react-bootstrap/Modal';

function ModaleCentro({
    modalTitle,
    modalBody,
    labelConfirm,
    onConfirm,
    onClose,
    show,
    disableConfirm = false,
}) {
  return (
    <Modal show={show} onHide={onClose} size='xl'>
        <Modal.Header closeButton>
          <Modal.Title>{modalTitle}</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {modalBody}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={onClose}>
            Close
          </Button>
          <Button variant="primary" onClick={onConfirm} disabled={disableConfirm}>
            {labelConfirm}
          </Button>
        </Modal.Footer>
      </Modal>
  );
}

export default ModaleCentro;