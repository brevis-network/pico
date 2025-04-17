use anyhow::{anyhow, Result};
use crossbeam::channel::{unbounded, Receiver, Sender};
use std::sync::Arc;

/// unidirectional unbounded channel, sender -> receiver
#[derive(Debug)]
pub struct SingleUnboundedChannel<T> {
    sender: Arc<Sender<T>>,
    receiver: Arc<Receiver<T>>,
}

impl<T> Default for SingleUnboundedChannel<T> {
    fn default() -> Self {
        let (sender, receiver) = unbounded();
        let sender = Arc::new(sender);
        let receiver = Arc::new(receiver);

        Self { sender, receiver }
    }
}

impl<T> SingleUnboundedChannel<T> {
    pub fn sender(&self) -> Arc<Sender<T>> {
        self.sender.clone()
    }

    pub fn receiver(&self) -> Arc<Receiver<T>> {
        self.receiver.clone()
    }

    pub fn send(&self, msg: T) -> Result<()> {
        self.sender
            .send(msg)
            .map_err(|err| anyhow!("failed to send msg: {err}"))?;

        Ok(())
    }

    pub fn recv(&self) -> Result<T> {
        let res = self
            .receiver
            .recv()
            .map_err(|err| anyhow!("failed to receive msg: {err}"))?;

        Ok(res)
    }
}

/// duplex unbounded endpoint includes a sender for type T and a receiver for type U
#[derive(Debug)]
pub struct DuplexUnboundedEndpoint<T, U> {
    sender: Sender<T>,
    receiver: Receiver<U>,
}

impl<T, U> DuplexUnboundedEndpoint<T, U> {
    pub fn new(sender: Sender<T>, receiver: Receiver<U>) -> Self {
        Self { sender, receiver }
    }

    pub fn sender(&self) -> &Sender<T> {
        &self.sender
    }

    pub fn receiver(&self) -> &Receiver<U> {
        &self.receiver
    }

    pub fn send(&self, msg: T) -> Result<()> {
        self.sender
            .send(msg)
            .map_err(|err| anyhow!("failed to send msg: {err}"))?;

        Ok(())
    }

    pub fn recv(&self) -> Result<U> {
        let res = self
            .receiver
            .recv()
            .map_err(|err| anyhow!("failed to receive msg: {err}"))?;

        Ok(res)
    }
}

/// duplex unbounded channel, endpoint1(sender<T>, receiver<U>) <-> endpoint2(sender<U>, Receiver<T>)
#[derive(Debug)]
pub struct DuplexUnboundedChannel<T, U> {
    endpoint1: Arc<DuplexUnboundedEndpoint<T, U>>,
    endpoint2: Arc<DuplexUnboundedEndpoint<U, T>>,
}

impl<T, U> Default for DuplexUnboundedChannel<T, U> {
    fn default() -> Self {
        let (sender1, receiver1) = unbounded();
        let (sender2, receiver2) = unbounded();

        let endpoint1 = Arc::new(DuplexUnboundedEndpoint::new(sender1, receiver2));
        let endpoint2 = Arc::new(DuplexUnboundedEndpoint::new(sender2, receiver1));

        Self {
            endpoint1,
            endpoint2,
        }
    }
}

impl<T, U> DuplexUnboundedChannel<T, U> {
    pub fn endpoint1(&self) -> Arc<DuplexUnboundedEndpoint<T, U>> {
        self.endpoint1.clone()
    }

    pub fn endpoint2(&self) -> Arc<DuplexUnboundedEndpoint<U, T>> {
        self.endpoint2.clone()
    }
}
