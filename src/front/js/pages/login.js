import React, { useContext } from "react";
import { Context } from "../store/appContext";
import "../../styles/home.css";

export const Login = () => {
  const { store, actions } = useContext(Context);
  //Test text
  /*    const fetchGenerico = async (endpoint, data, metodo) => {
           let url = process.env.URL_BACKEND
           let response = await fetch(url + endpoint, {
               method: metodo,
               headers: { "Content-Type": "application/json" },
               body: JSON.stringify(data)
           })
           return response;
       } */

  const login = async (e) => {
    e.preventDefault();
    console.log("Inside the fuction");

    const data = new FormData(e.target);
    console.log(data.get("password"));
    let email = data.get("email");
    let password = data.get("password");

    //let url = process.env.BACKEND_URL;
    let obj = {
      email: email,
      password: password,
    };

    let response = await actions.login("login", obj, 'POST');

    console.log(response);
    if (response.ok) {
      //console.log(response.statusText)
      //response = await response.json()
      alert(store.token);
    } else {
      alert("No se pudo hacer login");
      return;
    }
  };

  const prueba = async () => {
    let response = await actions.fetchProtegido("hellosecure");
    console.log(await response.json());
  };

  return (
    <>
      <div className="container">
        <form onSubmit={(e) => login(e)}>
          <div className="row d-flex">
            <div className="col">
              <div className="row">
                <h1>Email</h1>
              </div>
              <div className="row">
                <input
                  name="email"
                  placeholder="Escriba aquí su usuario"
                  type="email"
                />
              </div>
              <div className="row">
                <h1>Password</h1>
              </div>
              <div className="row">
                <input
                  name="password"
                  placeholder="Escriba aquí su clave"
                  type="string"
                />
              </div>
            </div>
            <div className="col">
              <div className="row">
                <button className="btn btn-outline-success" type="submit">
                  Login
                </button>
              </div>
              <div className="row">
                <button
                  className="btn btn-outline-success"
                  type="button"
                  onClick={() => prueba()}
                >
                  Prueba
                </button>
              </div>
            </div>
            <div className="col"></div>
          </div>
        </form>
      </div>
    </>
  );
};
