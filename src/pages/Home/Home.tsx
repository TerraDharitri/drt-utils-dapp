import styles from './styles.module.scss';

/*
 * Handle the component declaration.
 */

export const Home = () => (
  <div className={styles.home}>
    <h1 className={styles.title} data-testid='home-title'>
      Utilities for the Dharitri Blockchain
    </h1>

    <div className={styles.description} data-testid='home-description'>
      This page offers an easy to use pack of utilities necessary for
      interacting with the Dharitri Blockchain.
    </div>

    <div className={styles.description} data-testid='home-description'>
      Browse the menu on the left for Dharitri utilities.
    </div>
  </div>
);
