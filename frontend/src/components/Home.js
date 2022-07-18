import React from 'react';
import axios from 'axios';

async function provaAPI() {
    const instance = axios.create({
        baseURL: 'api/feeds/all/all/persistent.json',
        headers: {
          'Access-Control-Allow-Origin' : '*',
          'Access-Control-Allow-Methods':'GET',
          }
      });
      
    try {
      const response = await instance.get();
      console.log(response);
      console.log(response.data);
    } catch (error) {
      console.error(error);
    }
  }

function Home() {
    return (
        <div className='jumbotron'>
            <h1> Titolo Home Page </h1>
            <p> paragrafo home page </p>
            <p> paragrafo 2 home page </p>
            <button onClick={provaAPI}> prova api </button>
        </div>      
    );    
}

export default Home;